#in development
import argparse

args = argparse.ArgumentParser()

args.add_argument("--url", type=str, help="Specify a single URL.")
args.add_argument("--urlist", type=str, help="Use this when you have a URL wordlist.")
args = args.parse_args()

payload = "<<Checker>tag>"

def url_list():
    with open(args.urlist , 'r') as wordlist:
        for urls in wordlist:
            XSS_check(urls)

def single_url():
    XSS_check(args.url)


def XSS_check(url):
    if "?" not in url:
        return 0
    split_url = url.split("?")
    key, value = split_url
    if "&" in value:
        new_value = value.split('&')
        modified_second = []
        for new_values in new_value:
            key2,value2 = new_values.split("=")
            modified_second.append(f"{key2}={payload}")
        adc = "&".join(modified_second)
        final_url = (key + "?" + adc)
        print(final_url)
    else:
        primary_mod = []
        key3 , value3 = split_url
        again = value3.split("=")
        key4, value4 = again
        primary_mod.append(f"{key4}={payload}")
        final2_url = (key + "?" +"=".join(primary_mod))
        print(final2_url)


if __name__ == "__main__":
    if args.url:
        single_url()

    if args.urlist:
        url_list()

