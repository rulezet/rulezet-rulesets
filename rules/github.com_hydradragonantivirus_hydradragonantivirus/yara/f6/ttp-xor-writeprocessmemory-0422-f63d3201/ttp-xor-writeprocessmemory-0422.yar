rule TTP_XOR_WriteProcessMemory_0422 {
  strings:
    $key_0422 = { 53 50 [2] 61 72 [2] 67 47 [2] 49 47 [2] 76 5b }

  condition:
    any of them
}