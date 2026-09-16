rule TTP_XOR_WriteProcessMemory_0454 {
  strings:
    $key_0454 = { 53 26 [2] 61 04 [2] 67 31 [2] 49 31 [2] 76 2d }

  condition:
    any of them
}