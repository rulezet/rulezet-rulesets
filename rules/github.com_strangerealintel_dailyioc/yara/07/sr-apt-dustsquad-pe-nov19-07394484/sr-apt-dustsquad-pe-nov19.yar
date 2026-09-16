rule SR_APT_DustSquad_PE_Nov19 {
   meta:
      description = "Super Rule for APT DustSquad campaign Nov19"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/Rmy_Reserve/status/1197448735422238721"
      date = "2019-11-29"
   strings:
      $s1 = "EVP_PKEY_get1_DSA" fullword wide
      $s2 = "?WThe given \"%s\" local time is invalid (situated within the missing period prior to DST).8String index out of range (%d).  Mus" wide
      $s3 = "Address type not supported.\"%s: Circular links are not allowed\"Not enough data in buffer. (%d/%d)" fullword wide
      $s4 = "EVP_PKEY_CTX_get_operation" fullword wide
      $s5 = "OnGetPassword" fullword ascii
      $s6 = "Mozilla/5.0" fullword wide
      $s7 = ",Custom variant type (%s%.4x) is out of range/Custom variant type (%s%.4x) already used by %s*Custom variant type (%s%.4x) is no" wide
      $s8 = "WorkTarget" fullword ascii
      $s9 = "Generics.Collections}TList<System.DateUtils.TPair<System.Word,System.DateUtils.TLocalTimeZone.TYearlyChanges>>.:1" fullword ascii
      $s10 = "EVP_PKEY_encrypt_old" fullword wide
      $s11 = "EVP_PKEY_CTX_get0_pkey" fullword wide
      $s12 = "EVP_PKEY_encrypt_init" fullword wide
      $s13 = "EVP_PKEY_encrypt" fullword wide
      $s14 = "EVP_PKEY_CTX_get0_peerkey" fullword wide
      $s15 = "EVP_PKEY_get0" fullword wide
      $s16 = "X509_PUBKEY_get" fullword wide
      $s17 = "EVP_PKEY_CTX_get_cb" fullword wide
      $s18 = "EVP_PKEY_meth_set_encrypt" fullword wide
      $s19 = "EVP_PKEY_get1_RSA" fullword wide 
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}