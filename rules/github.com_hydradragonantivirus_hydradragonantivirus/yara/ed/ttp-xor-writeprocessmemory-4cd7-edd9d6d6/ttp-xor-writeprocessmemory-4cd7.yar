rule TTP_XOR_WriteProcessMemory_4cd7 {
  strings:
    $key_4cd7 = { 1b a5 [2] 29 87 [2] 2f b2 [2] 01 b2 [2] 3e ae }

  condition:
    any of them
}