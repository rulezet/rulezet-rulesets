rule TTP_XOR_WriteProcessMemory_fcfd {
  strings:
    $key_fcfd = { ab 8f [2] 99 ad [2] 9f 98 [2] b1 98 [2] 8e 84 }

  condition:
    any of them
}