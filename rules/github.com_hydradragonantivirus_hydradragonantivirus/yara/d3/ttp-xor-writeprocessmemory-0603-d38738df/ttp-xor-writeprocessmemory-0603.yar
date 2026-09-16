rule TTP_XOR_WriteProcessMemory_0603 {
  strings:
    $key_0603 = { 51 71 [2] 63 53 [2] 65 66 [2] 4b 66 [2] 74 7a }

  condition:
    any of them
}