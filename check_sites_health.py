import argparse
import requests
import whois
import socket
from datetime import datetime, timedelta
from urllib.parse import urlsplit


def get_args():
    parser = argparse.ArgumentParser(
        description="This script scan sites",
    )
    parser.add_argument('--file',
                        type=argparse.FileType('r'),
                        help='Path to text file with site urls')
    return parser.parse_args()


def load_urls4check(urls_list_file):
    return [url.strip() for url in urls_list_file]


def is_server_respond_with_200(url):
    try:
        response = requests.head(url)
    except:
        return False
    return response.status_code == requests.codes.ok


def get_domain_expiration_date(domain_name):
    if domain_name is not None:
        response = whois.query(domain_name)
        if response is not None:
            month_later = datetime.today() + timedelta(days=30)
            return(response.expiration_date > month_later)
        else:
            return False
    return True


def get_domain(url):
    parsed_url = urlsplit(url)
    netloc = "{0.netloc}".format(urlsplit(url))
    try:
        domain = netloc[:netloc.index(':')]
    except ValueError:
        domain = netloc
    try:
        socket.inet_aton(domain)
    except socket.error:
        return domain
    return None


def print_status(black_list):
    if not black_list:
        print('All is OK')
    else:
        for url in black_list:
            print('%s - not health!' % url)


def сheck_sites(url_list):
    black_list = []
    for url in url_list:
        server_status = is_server_respond_with_200(url)
        domain_status = get_domain_expiration_date(get_domain(url))
        if (not server_status or not domain_status):
            black_list.append(url)
    print_status(black_list)


if __name__ == '__main__':
    args = get_args()
    url_list = load_urls4check(args.file)
    сheck_sites(url_list)
