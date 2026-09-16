rule TTP_XOR_WriteProcessMemory_fa31 {
  strings:
    $key_fa31 = { ad 43 [2] 9f 61 [2] 99 54 [2] b7 54 [2] 88 48 }

  condition:
    any of them
}