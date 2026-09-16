rule WEBSHELL_Z_Webshell_2 {
   meta:
      description = "Detection for the z_webshell"
      author = "DHS NCCIC Hunt and Incident Response Team"
      date = "2018/01/25"
      old_rule_name = "z_webshell"
      md5 =  "2C9095C965A55EFC46E16B86F9B7D6C6"
      id = "9a54925f-de10-567f-a1ea-5e7522b47dfd"
   strings:
      $webshell_name = "public string z_progname =" nocase ascii wide
      $webshell_password = "public string Password =" nocase ascii wide
   condition:
      ( uint32(0) == 0x2040253c or uint32(0) == 0x7073613c )
      and filesize < 100KB
      and 2 of ($webshell_*)
}