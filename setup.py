# -*- coding: utf-8 -*-
#########################################################################
#
# Copyright (C) 2017 OSGeo
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
#########################################################################

from distutils.core import setup
import os


VERSION_FILEPATH = os.path.join(os.path.dirname(__file__), 'audit_logging', 'version')
version = open(VERSION_FILEPATH, 'r').read()
DIR = os.path.dirname(__file__)
README = open(os.path.join(DIR, 'README.md')).read()

setup(
    name='django-audit-logging',
    version=version,
    description="Logs events for auditing purposes.",
    long_description=README,
    classifiers=[
        "Development Status :: 4 - Beta"],
    keywords='',
    author='Dan Berry / Jivan Amara',
    author_email='Development@JivanAmara.net',
    license='GPL',
    packages=['audit_logging', 'audit_logging.migrations'],
    include_package_data=True,
    package_data={'audit_logging': ['version']},
    install_requires=[
        "Django >=1.8.7, <= 4.0.0",
    ],
)
