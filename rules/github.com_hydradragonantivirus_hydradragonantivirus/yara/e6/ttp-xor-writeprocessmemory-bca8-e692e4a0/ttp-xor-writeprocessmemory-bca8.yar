rule TTP_XOR_WriteProcessMemory_bca8 {
  strings:
    $key_bca8 = { eb da [2] d9 f8 [2] df cd [2] f1 cd [2] ce d1 }

  condition:
    any of them
}