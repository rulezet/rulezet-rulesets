rule TTP_XOR_WriteProcessMemory_9905 {
  strings:
    $key_9905 = { ce 77 [2] fc 55 [2] fa 60 [2] d4 60 [2] eb 7c }

  condition:
    any of them
}