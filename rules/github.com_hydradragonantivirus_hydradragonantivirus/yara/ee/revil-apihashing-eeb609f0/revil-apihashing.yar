rule REvil_ApiHashing {
  meta:
    description     = "API Hashing method in REvil / Sodinokibi"
    author          = "@larsborn"
    created_at      = "2021-03-27"
    example_hash_01 = "12d8bfa1aeb557c146b98f069f3456cc8392863a2f4ad938722cd7ca1a773b39"
    example_hash_02 = "5f56d5748940e4039053f85978074bde16d64bd5ba97f6f0026ba8172cb29e93"
    DaysofYARA      = "3/100"

  strings:
    $ = {
      55                       8B EC                    8B 55 08                 6A 2B                    58                       EB 0C                    69 C0 0F 01 00 00        42                       0F B6 C9                 03 C1                    8A 0A                    84 C9                    75 EE                    5D                       C3                     }

  condition:
    all of them
}