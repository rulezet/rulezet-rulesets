rule OpCloudHopper_lockdown {
   meta:
      description = "Tools related to Operation Cloud Hopper"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "8ca61cef74573d9c1d19b8191c23cbd2b7a1195a74eaba037377e5ee232b1dc5"
      id = "0500f19c-597b-5904-8401-35236215ff29"
   strings:
      $s1 = "lockdown.dll" fullword ascii
      $s3 = "mfeann.exe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}