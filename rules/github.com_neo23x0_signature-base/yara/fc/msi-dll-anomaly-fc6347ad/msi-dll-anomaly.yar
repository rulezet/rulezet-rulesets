rule msi_dll_Anomaly {
   meta:
      description = "Detetcs very small and supicious msi.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar"
      date = "2017-02-10"
      hash1 = "8c9048e2f5ea2ef9516cac06dc0fba8a7e97754468c0d9dc1e5f7bce6dbda2cc"
      id = "92cd5c51-ed84-5428-9105-50139f9289c8"
   strings:
      $x1 = "msi.dll.eng" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 15KB and filename == "msi.dll" and $x1
}