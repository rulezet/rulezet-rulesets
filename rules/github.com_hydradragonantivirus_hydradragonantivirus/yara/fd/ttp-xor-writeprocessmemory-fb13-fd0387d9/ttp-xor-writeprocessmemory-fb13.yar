rule TTP_XOR_WriteProcessMemory_fb13 {
  strings:
    $key_fb13 = { ac 61 [2] 9e 43 [2] 98 76 [2] b6 76 [2] 89 6a }

  condition:
    any of them
}