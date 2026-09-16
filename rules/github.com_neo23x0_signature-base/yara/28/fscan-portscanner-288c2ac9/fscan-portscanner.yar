rule Fscan_Portscanner {
   meta:
      description = "Fscan port scanner scan output / strings"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/JamesHabben/status/817112447970480128"
      date = "2017-01-06"
      id = "400383dc-8bc0-5e77-a3f3-d6ba9f4c3c0f"
   strings:
      $s1 = "Time taken:" fullword ascii
      $s2 = "Scan finished at" fullword ascii
      $s3 = "Scan started at" fullword ascii
   condition:
      filesize < 20KB and 3 of them
}