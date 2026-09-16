import "pe"
rule APT_DustSquad_PE_Nov19_2 {
   meta:
      description = "Detection Rule for APT DustSquad campaign Nov19"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/Rmy_Reserve/status/1197448735422238721"
      date = "2019-11-29"
      hash1 = "f5941f3d8dc8d60581d4915d06d56acba74f3ffad543680a85037a8d3bf3f8bc"
   strings:
      $x1 = "The credentials supplied were not complete, and could not be verified. Additional information can be returned from the context.4" wide
      $x2 = "The domain controller certificate used for smartcard logon has been revoked. Please contact your system administrator with the c" wide
      $s3 = "VTDictionary<System.Word,System.DateUtils.TLocalTimeZone.TYearlyChanges>.TKeyEnumeratorxsN" fullword ascii
      $s4 = ";The certificate chain was issued by an untrusted authority.7The message received was unexpected or badly formatted.;An unknown " wide
      $s5 = "The logon attempt failed;The credentials supplied to the package were not recognized4No credentials are available in the securit" wide
      $s6 = "8The message supplied for verification is out of sequence3No authority could be contacted for authentication.UThe function compl" wide
      $s7 = "The security context could not be established due to a failure in the requested quality of service (e.g. mutual authentication o" wide
      $s8 = "Error reading %s%s%s: %s\"Character index out of bounds (%d)" fullword wide
      $s9 = "OnExecutel" fullword ascii
      $s10 = "?WThe given \"%s\" local time is invalid (situated within the missing period prior to DST).8String index out of range (%d).  Mus" wide
      $s11 = "Address type not supported.\"%s: Circular links are not allowed\"Not enough data in buffer. (%d/%d)" fullword wide
      $s12 = "@TList<System.DateUtils.TLocalTimeZone.TYearlyChanges>.TEmptyFunc !@" fullword ascii
      $s13 = "dTList<System.DateUtils.TPair<System.Word,System.DateUtils.TLocalTimeZone.TYearlyChanges>>.TEmptyFunc !@" fullword ascii
      $s14 = "EVP_PKEY_CTX_get_operation" fullword wide
      $s15 = "http://www.borland.com/namespaces/Types" fullword wide
      $s16 = "OnGetPassword" fullword ascii
      $s17 = "OnGetPasswordExp" fullword ascii
      $s18 = "a1.exe" fullword ascii
      $s19 = "EIdSocksServerCommandError " fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      ( pe.imphash() == "7b3af4ed73c83b1a16f6f299b3eb654e" or ( 1 of ($x*) or 4 of them ) )
}