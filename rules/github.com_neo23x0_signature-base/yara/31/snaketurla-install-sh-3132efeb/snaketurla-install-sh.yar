rule SnakeTurla_Install_SH {
   meta:
      description = "Detects Snake / Turla Sample"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/QaOh4V"
      date = "2017-05-04"
      id = "68775c54-46f8-5d44-ba63-6726d2bb8016"
   strings:
      $s1 = "${TARGET_PATH}/installd.sh" ascii
      $s2 = "$TARGET_PATH2/com.adobe.update.plist" ascii
   condition:
   ( uint16(0) == 0x2123 and filesize < 20KB and all of them )
}