rule TTP_XOR_WriteProcessMemory_296a {
  strings:
    $key_296a = { 7e 18 [2] 4c 3a [2] 4a 0f [2] 64 0f [2] 5b 13 }

  condition:
    any of them
}