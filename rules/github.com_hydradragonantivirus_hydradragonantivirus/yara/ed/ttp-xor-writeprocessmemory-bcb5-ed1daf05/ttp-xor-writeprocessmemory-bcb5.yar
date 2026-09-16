rule TTP_XOR_WriteProcessMemory_bcb5 {
  strings:
    $key_bcb5 = { eb c7 [2] d9 e5 [2] df d0 [2] f1 d0 [2] ce cc }

  condition:
    any of them
}