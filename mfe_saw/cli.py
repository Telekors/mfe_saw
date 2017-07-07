# -*- coding: utf-8 -*-

"""Console script for mfe_saw."""

import click
try:
    from mfe_saw.esm import ESM
    from mfe_saw.datasource import Datasource, DevTree
except ModuleNotFoundError:
    from esm import ESM
    from datasource import Datasource, DevTree


@click.command()
def main(args=None):
    """Console script for mfe_saw."""

    CONFIG = 'config.ini'

    def get_config(conf=CONFIG):
        """

        """
        try:
            config = Config(conf, "esm")
            try:
                host = config.esmhost
                user = config.esmuser
                passwd = config.esmpass
            except AttributeError as e:
                click.echo(message=("Required settings not "
                                    "found in configfile: {}"
                                    .format(configfile)))
                sys.exit()
        except ValueError:
            click.echo(message="Config file not found: {}"
                       .format(configfile), err=True)
            sys.exit(1)

    @click.command()
    def login(host=host, user=user, passwd=passwd):
        """

        """
        esm = ESM()
        esm.login(host=host, user=user, passwd=passwd)

    @click.command()
    def version():
        """

        """
        click.echo(message="0.0.1")

if __name__ == "__main__":
    main()
