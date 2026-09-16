rule TTP_XOR_WriteProcessMemory_f987 {
  strings:
    $key_f987 = { ae f5 [2] 9c d7 [2] 9a e2 [2] b4 e2 [2] 8b fe }

  condition:
    any of them
}