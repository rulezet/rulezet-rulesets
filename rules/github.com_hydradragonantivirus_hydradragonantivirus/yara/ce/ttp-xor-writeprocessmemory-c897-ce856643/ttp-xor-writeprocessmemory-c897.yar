rule TTP_XOR_WriteProcessMemory_c897 {
  strings:
    $key_c897 = { 9f e5 [2] ad c7 [2] ab f2 [2] 85 f2 [2] ba ee }

  condition:
    any of them
}