rule TTP_XOR_WriteProcessMemory_7a03 {
  strings:
    $key_7a03 = { 2d 71 [2] 1f 53 [2] 19 66 [2] 37 66 [2] 08 7a }

  condition:
    any of them
}