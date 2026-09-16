rule TTP_XOR_WriteProcessMemory_0887 {
  strings:
    $key_0887 = { 5f f5 [2] 6d d7 [2] 6b e2 [2] 45 e2 [2] 7a fe }

  condition:
    any of them
}