description = [[
For each available CPE the script prints out known vulns (links to the correspondent info) and correspondent CVSS scores.

OFFLINE VERSION: This script uses a local offline database (cve_data.lua) instead of making remote requests.

Its work is pretty simple:
* work only when some software version is identified for an open port
* take all the known CPEs for that software (from the standard nmap -sV output)
* look up the CPE in the local offline database to find known vulns
* if no info is found this way, try to get it using the software name alone
* print the obtained info out

This offline version allows for vulnerability scanning without internet connectivity.
]]

---
-- @usage
-- nmap -sV --script vulners-offline.nse [--script-args mincvss=<arg_val>] <target>
--
-- @args vulners.mincvss Limit CVEs shown to those with this CVSS score or greater.
--
-- @output
--
-- 53/tcp   open     domain             ISC BIND DNS
-- | vulners-offline:
-- |   ISC BIND DNS:
-- |     CVE-2012-1667    8.5    cve    *EXPLOIT*
-- |     CVE-2002-0651    7.5    cve
-- |     CVE-2002-0029    7.5    cve
-- |     CVE-2015-5986    7.1    cve
-- |     CVE-2010-3615    5.0    cve    *EXPLOIT*
-- |     CVE-2006-0987    5.0    cve
-- |_    CVE-2014-3214    5.0    cve
--
-- Note: CVEs marked with *EXPLOIT* have known public exploits available in the database

author = 'gmedian AT vulners DOT com (offline version)'
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}


local json = require "json"
local string = require "string"
local table = require "table"
local nmap = require "nmap"
local stdnse = require "stdnse"

local api_version="1.2-offline"
local mincvss=stdnse.get_script_args("vulners.mincvss")
mincvss = tonumber(mincvss) or 0.0

-- Load the offline CVE database
local cve_data = stdnse.silent_require("cve_data")

-- Check if database loaded successfully
if not cve_data then
  stdnse.debug1("vulners-offline: Warning - cve_data.lua not found or failed to load")
end

portrule = function(host, port)
  -- Accept any open port (service-independent)
  -- We'll handle missing version info in the action function
  return true
end

local cve_meta = {
  __tostring = function(me)
      return ("\t%s\t%s\t%s%s"):format(me.id, me.cvss or "", me.type, me.is_exploit and '\t*EXPLOIT*' or '')
  end,
}

---
-- Return a table with all the found cve's from the offline database
--
-- @param cpe string, the CPE to look up
-- @param vers string, the version to look up
-- @param dbtype string, either "cpe" or "product"
--
function make_links_offline(cpe, vers, dbtype)
  local output = {}
  
  if not cve_data then
    stdnse.debug2("vulners-offline: Database not available for " .. dbtype .. " lookup: " .. cpe)
    return nil
  end
  
  if dbtype == "cpe" then
    -- Direct CPE lookup
    if cve_data.cpe and cve_data.cpe[cpe] then
      stdnse.debug2("vulners-offline: Found exact CPE entry: " .. cpe)
      for _, vuln in ipairs(cve_data.cpe[cpe]) do
        local v = {
          id = vuln.id,
          type = vuln.type or "cve",
          is_exploit = vuln.is_exploit or false,
          cvss = tonumber(vuln.cvss) or 0.0,
        }
        
        if not v.cvss or (v.cvss == 0 and v.is_exploit) or mincvss <= v.cvss then
          setmetatable(v, cve_meta)
          output[#output+1] = v
        end
      end
    end
    
    -- If exact match not found, try wildcard version
    if #output == 0 then
      -- Replace version with wildcard
      local cpe_wildcard = cpe:gsub(":([^:]+)$", ":*")
      if cpe_wildcard ~= cpe and cve_data.cpe and cve_data.cpe[cpe_wildcard] then
        stdnse.debug2("vulners-offline: Found wildcard CPE entry: " .. cpe_wildcard)
        for _, vuln in ipairs(cve_data.cpe[cpe_wildcard]) do
          local v = {
            id = vuln.id,
            type = vuln.type or "cve",
            is_exploit = vuln.is_exploit or false,
            cvss = tonumber(vuln.cvss) or 0.0,
          }
          
          if not v.cvss or (v.cvss == 0 and v.is_exploit) or mincvss <= v.cvss then
            setmetatable(v, cve_meta)
            output[#output+1] = v
          end
        end
      end
    end
    
    if #output == 0 then
      stdnse.debug2("vulners-offline: No CPE entry found for: " .. cpe)
    end
  elseif dbtype == "product" then
    -- Product/version lookup
    if cve_data.product and cve_data.product[cpe] then
      stdnse.debug2("vulners-offline: Found product entry: " .. cpe)
      local product_data = cve_data.product[cpe]
      local vulns = product_data[vers] or product_data["*"]
      
      if vulns then
        stdnse.debug2("vulners-offline: Found vulnerabilities for " .. cpe .. " version " .. vers)
        for _, vuln in ipairs(vulns) do
          local v = {
            id = vuln.id,
            type = vuln.type or "cve",
            is_exploit = vuln.is_exploit or false,
            cvss = tonumber(vuln.cvss) or 0.0,
          }
          
          if not v.cvss or (v.cvss == 0 and v.is_exploit) or mincvss <= v.cvss then
            setmetatable(v, cve_meta)
            output[#output+1] = v
          end
        end
      else
        stdnse.debug2("vulners-offline: No vulnerabilities for " .. cpe .. " version " .. vers)
      end
    else
      stdnse.debug2("vulners-offline: No product entry found for: " .. cpe)
    end
  end

  if #output > 0 then
    -- Sort the acquired vulns by the CVSS score
    table.sort(output, function(a, b)
        return a.cvss > b.cvss or (a.cvss == b.cvss and a.id > b.id)
      end)
    stdnse.debug2("vulners-offline: Returning " .. #output .. " vulnerabilities")
    return output
  end
  
  return nil
end


---
-- Get results from offline database
--
-- @param what string, the software/cpe to query
-- @param vers string, the version query argument
-- @param dbtype string, the type query argument ("cpe" or "product")
--
function get_results(what, vers, dbtype)
  return make_links_offline(what, vers, dbtype)
end


---
-- Calls <code>get_results</code> for type="software"
--
-- It is called from <code>action</code> when nothing is found for the available cpe's
--
-- @param software string, the software name
-- @param version string, the software version
--
function get_vulns_by_software(software, version)
  return get_results(software, version, "product")
end


---
-- Calls <code>get_results</code> for type="cpe"
--
-- Takes the version number from the given <code>cpe</code> and tries to get the result.
-- If none found, changes the given <code>cpe</code> a bit in order to possibly separate version number from the patch version
-- And makes another attempt.
-- Having failed returns an empty string.
--
-- @param cpe string, the given cpe
--
function get_vulns_by_cpe(cpe)
  local vers_regexp=":([%d%.%-%_]+)([^:]*)$"

  -- NOTE: take only the numeric part of the version
  local _, _, vers = cpe:find(vers_regexp)

  if not vers then
    stdnse.debug2("vulners-offline: Could not extract version from CPE: " .. cpe)
    return
  end

  local output = get_results(cpe, vers, "cpe")

  if not output then
    local new_cpe

    new_cpe = cpe:gsub(vers_regexp, ":%1:%2")
    stdnse.debug2("vulners-offline: Retrying with modified CPE: " .. new_cpe)
    output = get_results(new_cpe, vers, "cpe")
  end

  return output
end


action = function(host, port)
  local tab=stdnse.output_table()
  local changed=false
  local response
  local output
  local port_str = tostring(port.number) .. "/" .. port.protocol
  
  -- Validate that we have version information
  if not port.version or not port.version.version then
    stdnse.debug1("vulners-offline: No version information available for port " .. port_str)
    return
  end
  
  stdnse.debug1("vulners-offline: Scanning port " .. port_str .. " - " .. (port.version.product or "unknown") .. " " .. port.version.version)
  
  -- Try CPE-based lookups if CPEs are available
  if port.version.cpe and #port.version.cpe > 0 then
    stdnse.debug1("vulners-offline: Found " .. #port.version.cpe .. " CPE(s) for this service")
    for i, cpe in ipairs(port.version.cpe) do
      stdnse.debug2("vulners-offline: Checking CPE " .. i .. ": " .. cpe)
      output = get_vulns_by_cpe(cpe)
      if output then
        tab[cpe] = output
        changed = true
        stdnse.debug1("vulners-offline: Found " .. #output .. " vulnerabilities for CPE: " .. cpe)
      else
        stdnse.debug1("vulners-offline: No vulnerabilities found for CPE: " .. cpe)
      end
    end
  else
    stdnse.debug2("vulners-offline: No CPEs available for this port")
  end

  -- NOTE: Try product name/version lookup if no CPE matches found
  if not changed then
    local product = port.version.product or "unknown"
    local version = port.version.version or "unknown"
    
    stdnse.debug1("vulners-offline: Attempting product lookup for " .. product .. " " .. version)
    output = get_vulns_by_software(product, version)
    if output then
      local vendor_version = product .. " " .. version
      tab[vendor_version] = output
      changed = true
      stdnse.debug1("vulners-offline: Found " .. #output .. " vulnerabilities for product: " .. vendor_version)
    else
      stdnse.debug2("vulners-offline: No vulnerabilities found for product: " .. product .. " " .. version)
    end
  end

  if (not changed) then
    stdnse.debug1("vulners-offline: No vulnerabilities found for port " .. port_str)
    local empty_tab = stdnse.output_table()
    empty_tab["message"] = "No CVE found"
    return empty_tab
  end
  
  stdnse.debug1("vulners-offline: Returning results for port " .. port_str)
  return tab
end
