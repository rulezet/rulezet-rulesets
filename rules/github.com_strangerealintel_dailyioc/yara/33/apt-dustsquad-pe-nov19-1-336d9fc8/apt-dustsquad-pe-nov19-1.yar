import "pe"
rule APT_DustSquad_PE_Nov19_1 {
   meta:
      description = "Detection Rule for APT DustSquad campaign Nov19"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/Rmy_Reserve/status/1197448735422238721"
      date = "2019-11-29"
      hash1 = "105402dd65ec1c53b6db68a0e21fcee5b72e161bc3b53e644695a4c9fae32909"
   strings:
      $x1 = "The credentials supplied were not complete, and could not be verified. Additional information can be returned from the context.4" wide
      $s2 = "The logon attempt failed;The credentials supplied to the package were not recognized4No credentials are available in the securit" wide
      $s3 = "Address type not supported.\"%s: Circular links are not allowed\"Not enough data in buffer. (%d/%d)" fullword wide
      $s4 = "@TList<System.DateUtils.TLocalTimeZone.TYearlyChanges>.TEmptyFunc" fullword ascii
      $s5 = "Error getting SSL method.%Error setting File Descriptor for SSL!Error binding data to SSL socket.'Maximum number of line allowed" wide
      $s6 = "Checksum error in the encrypted file %s. Corrupt file or wrong password." fullword wide
      $s7 = "Download: " fullword wide
      $s8 = "An attempt was made by this server to make a Kerberos constrained delegation request for a target outside of the server's realm." wide
      $s9 = "D:\\Projects\\WinRAR\\rar\\build\\rar32\\Release\\RAR.pdb" fullword ascii
      $s10 = " computersystem get Name /format:list" fullword wide
      $s11 = "Enter password (will not be echoed) for %s: " fullword wide
      $s12 = "Remove: " fullword wide
      $s13 = "rarinfo.log" fullword wide
      $s14 = "?WThe given \"%s\" local time is invalid (situated within the missing period prior to DST).8String index out of range (%d).  Mus" wide
      $s15 = "OnExecuteH}H" fullword ascii
      $s16 = "ffffffffffffffg" fullword ascii 
      $s17 = "Successfull API call7Not enough memory is available to complete this request" wide
      $s18 = "The handle specified is invalid'The function reques" wide
      $s19 = "1????????.*" wide
      $s20 = "/d.php?servers" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      ( pe.imphash() == "9a622f807282a29fb32811b734622622" or ( 1 of ($x*) or 4 of them ) )
}