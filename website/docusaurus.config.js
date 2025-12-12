// @ts-check
// `@type` JSDoc annotations allow editor autocompletion and type checking
// (when paired with `@ts-check`).
// There are various equivalent ways to declare your Docusaurus config.
// See: https://docusaurus.io/docs/api/docusaurus-config

import {themes as prismThemes} from 'prism-react-renderer';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Agentic Community',
  tagline: '',
  // favicon: '',

  // Set the production url of your site here
  url: 'https://agentic-community.github.io',
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: '/',

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'agentic-community', // Usually your GitHub org/user name.
  projectName: 'website', // Usually your repo name.

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang. For example, if your site is Chinese, you
  // may want to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: './sidebars.js',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      // Replace with your project's social card
      // image: '',
      navbar: {
        title: 'Home',
        // logo: {
        //   alt: 'Home Logo',
        //   src: '',
        // },
        items: [
          {
            label: 'About',
            to: '/docs/about',
            position: 'left',
          },
          {
            label: 'Artifacts',
            to: '/docs/artifacts',
            position: 'left',
          },
          {
            'aria-label': 'Community Calendar',
            'className': 'navbar--calendar-link',
            'href': "https://calendar.google.com/calendar/embed?src=c_c2c61707db4ec15fc107e5d0f2e18714f06fe8b12c85812f0c6b99321ae4d354%40group.calendar.google.com&ctz=America%2FLos_Angeles",
            'position': 'right',
          },
          {
            'aria-label': 'Notes',
            'className': 'navbar--notes-link',
            'href': "https://docs.google.com/document/d/1xZFILz12oDnjOkBTlJAE5zzZpxGy2jeK6oziN13ZFdw/edit?usp=sharing",
            'position': 'right',
          },
          {
            'aria-label': 'Slack Channel',
            'className': 'navbar--slack-link',
            'href': "https://cloud-native.slack.com/archives/C08R46FF27R",
            'position': 'right',
          },
          {
            'aria-label': 'GitHub Repository',
            'className': 'navbar--github-link',
            'href': 'https://github.com/agentic-community',
            'position': 'right',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Docs',
            items: [
              {
                label: 'About',
                to: '/docs/about',
              },
            ],
          },
          {
            title: 'More',
            items: [
              {
                label: 'GitHub',
                href: 'https://github.com/agentic-community',
              },
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} Agentic Community`,
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
      },
      imageZoom: {
        // CSS selector to apply the plugin to, defaults to '.markdown img'
        selector: '.markdown img',
        // Optional medium-zoom options
        // see: https://www.npmjs.com/package/medium-zoom#options
        options: {
          margin: 24,
          background: '#FFFFFF',
          scrollOffset: 0,
          //container: '#zoom-container',
          //template: '#zoom-template',
        },
      },
    }),
  plugins: [
    'plugin-image-zoom',
    require.resolve('docusaurus-lunr-search')
  ],
};

export default config;
