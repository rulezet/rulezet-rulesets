rule TTP_XOR_WriteProcessMemory_cab3 {
  strings:
    $key_cab3 = { 9d c1 [2] af e3 [2] a9 d6 [2] 87 d6 [2] b8 ca }

  condition:
    any of them
}