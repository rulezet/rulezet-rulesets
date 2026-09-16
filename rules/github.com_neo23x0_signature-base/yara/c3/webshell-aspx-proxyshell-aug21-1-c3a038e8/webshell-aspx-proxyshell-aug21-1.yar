rule WEBSHELL_ASPX_ProxyShell_Aug21_1 {
   meta:
      description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be PST) and extension"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.bleepingcomputer.com/news/microsoft/microsoft-exchange-servers-are-getting-hacked-via-proxyshell-exploits/"
      date = "2021-08-13"
      id = "8f01cbda-b1cf-5556-9f6a-e709df6dadb2"
   condition:
      uint32(0) == 0x4e444221  
      and extension == ".aspx"
}