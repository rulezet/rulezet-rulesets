rule TTP_XOR_WriteProcessMemory_dba2 {
  strings:
    $key_dba2 = { 8c d0 [2] be f2 [2] b8 c7 [2] 96 c7 [2] a9 db }

  condition:
    any of them
}