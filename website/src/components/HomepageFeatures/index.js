import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

const FeatureList = [
    {
        Svg: 'a',
        title: 'Agent Platform Foundation',
        description: (
            <>
                Building comprehensive architectural reference implementations for
                secure, scalable AI agent deployments with focus on security,
                scalability, and multi-tenancy.
            </>
        ),
    },
    {
        Svg: 'a',
        title: 'Interoperability Standards',
        description: (
            <>
                Developing and testing standards-based protocols to ensure seamless
                agent interactions across diverse platforms, including API specifications
                and integration patterns.
            </>
        ),
    },
    {
        Svg: 'a',
        title: 'Community-Driven Innovation',
        description: (
            <>
                Leveraging open source technologies and cloud-native principles to
                enable scalable, reliable, and secure agent development for
                organizations of all sizes.
            </>
        ),
    },
];

function Feature({ Svg, title, description}) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <Svg className={styles.featureSvg} role="img" />
      </div>
      <div className="text--center padding-horiz--md">
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures() {
  return (
      <section className={styles.features}>
          <div className="container">
              <div className="row">
                  {FeatureList.map((props, idx) => (
                      <Feature key={idx} {...props} />
                  ))}
              </div>

              <div className={styles.principles}>
                  <h2>Our Principles</h2>
                  <div className={styles.principlesList}>
                      <div className={styles.principle}>Focus on Open Source</div>
                      <div className={styles.principle}>Modular Composable Architecture</div>
                      <div className={styles.principle}>Standards-driven Interoperability</div>
                      <div className={styles.principle}>Community Empowerment</div>
                  </div>
              </div>
          </div>
      </section>
  );
}
