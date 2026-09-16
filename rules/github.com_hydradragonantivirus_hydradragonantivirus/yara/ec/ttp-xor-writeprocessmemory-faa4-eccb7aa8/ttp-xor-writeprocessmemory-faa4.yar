rule TTP_XOR_WriteProcessMemory_faa4 {
  strings:
    $key_faa4 = { ad d6 [2] 9f f4 [2] 99 c1 [2] b7 c1 [2] 88 dd }

  condition:
    any of them
}