Hatem Aliyan  to  Everyone 9:42
import re


def get_ip_address() -> str:
    """
    Prompts the user to enter an IP address and returns it as a string.

    Returns:
        A string representing the user's input.
    """
    while True:
        ip_str = input("Enter IP address: ")
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_str):
            return ip_str
        print("Invalid IP address. Please try again.")


def get_subnet_mask() -> int:
    """
    Prompts the user to enter a subnet mask in CIDR notation and returns it as an integer.

    Returns:
        An integer representing the subnet mask in CIDR notation.
    """
    while True:
        subnet_mask_str = input("Enter subnet mask in CIDR notation (optional): ")
        if subnet_mask_str == '':
            return None
        elif re.match(r'^\d{1,2}$', subnet_mask_str):
            return int(subnet_mask_str)
        print("Invalid subnet mask. Please try again.")


def get_partitioning_type() -> str:
    """
    Prompts the user to choose whether to partition by number of hosts or number of subnets.

    Returns:
        A string representing the user's choice.
    """
    while True:
        partitioning_type = input("Will the partitioning be according to number of hosts or number of subnets? ")
        if partitioning_type.lower() == 'hosts' or partitioning_type.lower() == 'subnets':
            return partitioning_type.lower()
        print("Invalid partitioning type. Please try again.")


def get_num() -> int:
    """
    Prompts the user to enter a number of hosts or subnets.

    Returns:
        An integer representing the user's input.
    """
    while True:
        num_str = input("Enter number of hosts/subnets: ")
        if re.match(r'^\d+$', num_str):
            return int(num_str)
        print("Invalid number. Please try again.")


def calculate_subnet():
    """
    Calculates and prints information about a subnet based on user input.
    """
    ip_address = get_ip_address()
    subnet_mask = get_subnet_mask()
    if subnet_mask is None:
        subnet_mask = 24
    partitioning_type = get_partitioning_type()
    num = get_num()

    subnet_mask_decimal = '.'.join([str((0xffffffff << (32 - subnet_mask) >> i) & 0xff) for i in [24, 16, 8, 0]])
    cidr = str(subnet_mask)
    num_hosts = 2 ** (32 - subnet_mask) - 2
    num_subnets = 2 ** (32 - subnet_mask)

    ip_octets = [int(octet) for octet in ip_address.split('.')]
    network_address = '.'.join([str(ip_octets[i] & int(subnet_mask_decimal.split('.')[i])) for i in range(4)])
    broadcast_address = '.'.join([str(ip_octets[i] | (255 - int(subnet_mask_decimal.split('.')[i]))) for i in range(4)])

    print("1. Subnet mask (in mask decimal format):", subnet_mask_decimal)
    print("2. Subnet in CIDR:", cidr)
    print("3. Number of hosts:", num_hosts)
    print("4. Number of subnets:", num_subnets)
    print("5. Network address:", network_address)
    print("   Broadcast address:", broadcast_address)


if __name__ == '__main__':
    calculate_subnet()