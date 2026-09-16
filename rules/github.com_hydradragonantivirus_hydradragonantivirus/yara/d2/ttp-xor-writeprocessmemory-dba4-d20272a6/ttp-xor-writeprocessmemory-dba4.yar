rule TTP_XOR_WriteProcessMemory_dba4 {
  strings:
    $key_dba4 = { 8c d6 [2] be f4 [2] b8 c1 [2] 96 c1 [2] a9 dd }

  condition:
    any of them
}