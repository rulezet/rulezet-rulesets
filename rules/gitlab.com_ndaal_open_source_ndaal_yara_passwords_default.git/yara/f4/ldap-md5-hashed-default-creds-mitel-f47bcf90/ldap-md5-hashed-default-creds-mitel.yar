rule ldap_md5_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a1="{MD5}VLUwclQO7rj46TQ+cfKBdg=="
    $a2="{MD5}qbe6cHg7YX6ZmNxN2C6zxQ=="
    $a3="{MD5}lzhCYbi7+WbfFuWtUJki2w=="
    $a4="{MD5}KzUbvAahUGqHd8yMZlGFQA=="
    $a5="{MD5}VLUwclQO7rj46TQ+cfKBdg=="
    $a6="{MD5}rHtN/lGdp5YOsnuY+HgKnw=="
    $a7="{MD5}lzhCYbi7+WbfFuWtUJki2w=="
    $a8="{MD5}YhgdG/cvbery+mETDHK7Dg=="
    $a9="{MD5}VLUwclQO7rj46TQ+cfKBdg=="
    $a10="{MD5}PSFyQYzjBcfRbUsFWXxqWQ=="
    $a11="{MD5}ISMvKXpXpadDiUoOSoAfww=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}