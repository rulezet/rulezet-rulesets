rule TTP_XOR_WriteProcessMemory_fb31 {
  strings:
    $key_fb31 = { ac 43 [2] 9e 61 [2] 98 54 [2] b6 54 [2] 89 48 }

  condition:
    any of them
}