rule WEBSHELL_Z_WebShell_1 {
   meta:
      author = "NCSC"
      description = "Detects Z Webshell from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      old_rule_name = "Z_WebShell"
      hash = "ace12552f3a980f1eed4cadb02afe1bfb851cafc8e58fb130e1329719a07dbf0"
      id = "f4b50760-bd3a-5e1f-bf32-50f16a42c381"
   strings:
      $ = "Z_PostBackJS" ascii wide
      $ = "z_file_download" ascii wide
      $ = "z_WebShell" ascii wide
      $ = "1367948c7859d6533226042549228228" ascii wide
   condition:
      3 of them
}