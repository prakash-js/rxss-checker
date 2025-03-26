import argparse
import requests
import re

args = argparse.ArgumentParser()

args.add_argument("--url", type=str, help="Specify a single URL.")
args.add_argument("--urlist", type=str, help="Use this when you have a URL wordlist.")
args = args.parse_args()

payload = "<<Checker>tag>"
element = r'<<Checker>tag>'


def url_list():
    with open(args.urlist , 'r') as wordlist:
        for urls in wordlist:
            XSS_check(urls)

def single_url():
    XSS_check(args.url)

print("If Vulnerable URL found it will Display")


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
        joining = "&".join(modified_second)
        final_url = (key + "?" + joining)
        try:
            response = requests.get(final_url)
            if response.status_code == 200:
                output = response.text
                match = re.search(element, output)
                if match:
                    print(f"{final_url} \nThe URL is potentially vulnerable to XSS as it reflects <>.")
                else:
                    return 0
        except requests.exceptions.RequestException as e:
            pass

    else:
        primary_mod = []
        key3 , value3 = split_url
        again = value3.split("=")
        key4, value4 = again
        primary_mod.append(f"{key4}={payload}")
        final2_url = (key + "?" +"=".join(primary_mod))
        try:
            response2 = requests.get(final2_url)
            if response2.status_code == 200:
                output2 = response2.text
                match = re.search(element, output2)
                if match:
                    print(f"{final2_url} \nThe URL is potentially vulnerable to XSS as it reflects <>.")
                else:
                    return 0
        except requests.exceptions.RequestException as e:
            pass


if __name__ == "__main__":
    if args.url:
        single_url()

    if args.urlist:
        url_list()

