rule url {
    meta:
        info = "URL Strings"

    strings:
        $url_regex = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/ wide ascii

    condition:
        $url_regex
}