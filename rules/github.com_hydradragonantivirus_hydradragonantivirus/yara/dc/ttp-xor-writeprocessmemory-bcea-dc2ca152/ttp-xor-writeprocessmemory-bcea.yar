rule TTP_XOR_WriteProcessMemory_bcea {
  strings:
    $key_bcea = { eb 98 [2] d9 ba [2] df 8f [2] f1 8f [2] ce 93 }

  condition:
    any of them
}