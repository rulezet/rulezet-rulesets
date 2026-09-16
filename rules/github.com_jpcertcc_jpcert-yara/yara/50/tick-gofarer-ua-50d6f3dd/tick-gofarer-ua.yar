rule tick_Gofarer_ua {
    meta:
      description = "Gofarer malware"
      author = "JPCERT/CC Incident Response Group"
      hash = "9a7e18ab6e774a76e3bd74709e9435449915329a1234364b4ef1b0d5d69158db"

	  strings:
        $ua = "Mozilla/4.0+(compatible;+MSIE+8.0;+Windows+NT+6.1;+Trident/4.0;+SLCC2;+.NET+CLR+2.0.50727;+.NET4.0E)"

    condition:
        all of them
}