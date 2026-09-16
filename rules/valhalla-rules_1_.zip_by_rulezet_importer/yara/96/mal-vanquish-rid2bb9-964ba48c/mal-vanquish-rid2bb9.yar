rule MAL_vanquish_RID2BB9 : DEMO MAL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file vanquish.dll"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 09:18:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, MAL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "You cannot delete protected files/folders! Instead, your attempt has been logged" 
      $s8 = "?VCreateProcessA@@YGHPBDPADPAU_SECURITY_ATTRIBUTES@@2HKPAX0PAU_STARTUPINFOA@@PAU" 
      $s9 = "?VFindFirstFileExW@@YGPAXPBGW4_FINDEX_INFO_LEVELS@@PAXW4_FINDEX_SEARCH_OPS@@2K@Z" 
   condition: 
      all of them
}