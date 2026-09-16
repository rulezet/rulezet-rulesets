rule TTP_XOR_WriteProcessMemory_bc75 {
  strings:
    $key_bc75 = { eb 07 [2] d9 25 [2] df 10 [2] f1 10 [2] ce 0c }

  condition:
    any of them
}