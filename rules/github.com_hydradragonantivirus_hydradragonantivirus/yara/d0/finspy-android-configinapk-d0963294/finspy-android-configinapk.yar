rule finspy_android_configinapk: android apkhideconfig finspy {
  meta:
    description = "Detect FinFisher FinSpy configuration in APK file. Probably the original FinSpy version."
    date        = "2020/08/05"
    reference   = "https://github.com/devio/FinSpy-Tools"
    author      = "Esther Onfroy a.k.a U+039b - *@0x39b.fr (https://twitter.com/u039b)"
    warning     = "May have some False Positive"

  strings:
    $re = /\x50\x4B\x01\x02[\x00-\xff]{32}[A-Za-z0-9+\/]{6}/

  condition:
    uint32(0) == 0x04034b50 and $re and (#re > 50)
}