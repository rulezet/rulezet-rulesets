rule TTP_XOR_WriteProcessMemory_9922 {
  strings:
    $key_9922 = { ce 50 [2] fc 72 [2] fa 47 [2] d4 47 [2] eb 5b }

  condition:
    any of them
}