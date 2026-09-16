rule TTP_XOR_WriteProcessMemory_ad92 {
  strings:
    $key_ad92 = { fa e0 [2] c8 c2 [2] ce f7 [2] e0 f7 [2] df eb }

  condition:
    any of them
}