rule TTP_XOR_WriteProcessMemory_0cfa {
  strings:
    $key_0cfa = { 5b 88 [2] 69 aa [2] 6f 9f [2] 41 9f [2] 7e 83 }

  condition:
    any of them
}