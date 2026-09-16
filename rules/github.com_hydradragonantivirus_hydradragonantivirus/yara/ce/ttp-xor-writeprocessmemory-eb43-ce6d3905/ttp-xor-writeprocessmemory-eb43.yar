rule TTP_XOR_WriteProcessMemory_eb43 {
  strings:
    $key_eb43 = { bc 31 [2] 8e 13 [2] 88 26 [2] a6 26 [2] 99 3a }

  condition:
    any of them
}