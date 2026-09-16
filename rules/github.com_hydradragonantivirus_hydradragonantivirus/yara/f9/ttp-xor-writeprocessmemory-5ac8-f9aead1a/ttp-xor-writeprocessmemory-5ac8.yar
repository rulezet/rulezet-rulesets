rule TTP_XOR_WriteProcessMemory_5ac8 {
  strings:
    $key_5ac8 = { 0d ba [2] 3f 98 [2] 39 ad [2] 17 ad [2] 28 b1 }

  condition:
    any of them
}