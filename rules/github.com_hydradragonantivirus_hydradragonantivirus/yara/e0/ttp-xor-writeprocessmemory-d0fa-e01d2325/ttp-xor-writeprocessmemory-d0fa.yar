rule TTP_XOR_WriteProcessMemory_d0fa {
  strings:
    $key_d0fa = { 87 88 [2] b5 aa [2] b3 9f [2] 9d 9f [2] a2 83 }

  condition:
    any of them
}