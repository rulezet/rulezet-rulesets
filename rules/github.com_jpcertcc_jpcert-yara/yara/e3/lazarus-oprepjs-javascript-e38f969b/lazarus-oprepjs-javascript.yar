rule Lazarus_oprepjs_javascript {
   meta:
      description = "JS downloader for Lazarus"
      author = "JPCERT/CC Incident Response Group"
      hash = "d69691996067c04fdb5595cf1512aca8928ee64511b4b3674197015414d014c8"

   strings:
      $enc1 = "writeFileSync" ascii
      $enc2 = "Login Data" ascii
      $enc3 = "copyFile" ascii
      $enc4 = ".replace(" ascii
      $enc5 = "/client" ascii
      $enc6 = "t[e], a += t[10 + e], $ += t[20 + e], r += t[30 + e];" ascii
      $enc7 = "${c}${$}_${l}_${t}" ascii
      $enc8 = "/.npl" ascii
      $enc9 = "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/" ascii
      $enc10 = "/Library/Application Support/Google/Chrome/" ascii
      $enc11 = "includes(\".ldb\")" ascii
      $key1 = "30e5e005f625f45e9561c0c105466fd72be45e961fc88abc59012cb9b7fd091a" ascii
      $key2 = "eafb61b23c14874c10945b466cfef16b" ascii
      $key3 = "7a0508b2eb487b05be4aa5ea01c5e15d" ascii


   condition:
      6 of ($enc*) or all of ($key*)
}