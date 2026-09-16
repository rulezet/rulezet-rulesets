rule capa_asp_obfuscation_multi: WEBSHELL PROD {
  meta:
    description = "ASP obfuscation functions which have to be used multiple times, e.g. for each character"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/02/06"
    score       = 50

  strings:
                        $o4 = "\\x8" wide ascii
    $o5 = "\\x9" wide ascii
        $o6 = "\\61" wide ascii
    $o7 = "\\44" wide ascii
    $o8 = "\\112" wide ascii
    $o9 = "\\120" wide ascii
            
    $m_multi_one1 = "Replace(" wide ascii
    $m_multi_one2 = "Len(" wide ascii
    $m_multi_one3 = "Mid(" wide ascii
    $m_multi_one4 = "mid(" wide ascii
    $m_multi_one5 = ".ToString(" wide ascii

    

    $m_fp1 = "Author: Andre Teixeira - andret@microsoft.com"  

  condition:
    (
      filesize < 100KB and
      not any of ($m_fp*) and
      (
                (#o4 + #o5 + #o6 + #o7 + #o8 + #o9) > 20
      )
    ) or (
      filesize < 5KB and
      (
                (#o4 + #o5 + #o6 + #o7 + #o8 + #o9) > 5 or
        (
                    (#m_multi_one1 + #m_multi_one2 + #m_multi_one3 + #m_multi_one4 + #m_multi_one5) > 3
        )

      )
    ) or (
      filesize < 700 and
      (
                (#o4 + #o5 + #o6 + #o7 + #o8 + #o9) > 3 or
        (#m_multi_one1 + #m_multi_one2 + #m_multi_one3 + #m_multi_one4 + #m_multi_one5) > 2
      )
    )
}