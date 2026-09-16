rule TTP_XOR_WriteProcessMemory_f9bb {
  strings:
    $key_f9bb = { ae c9 [2] 9c eb [2] 9a de [2] b4 de [2] 8b c2 }

  condition:
    any of them
}