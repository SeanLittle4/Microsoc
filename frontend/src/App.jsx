import { useState } from 'react';
import Home from './components/Home';
import Survey from './Survey';
import MisconfigGuide from './components/MisconfigGuide';
import GordonLoebWalkthrough from './components/GordonLoebWalkthrough';

// ─── view values ─────────────────────────────────────────────────────────────
// 'home'      — landing dashboard
// 'survey'    — risk assessment (owns sub-navigation for economic/misconfig)
// 'misconfig' — standalone misconfig guide (no threat model context)
// 'economic'  — economic model launched directly from home results banner

export default function App() {
  const [view,            setView]           = useState('home');
  const [lastThreatModel, setLastThreatModel] = useState(null);
  const [lastAnswers,     setLastAnswers]     = useState({});
  const [resumeResults,   setResumeResults]   = useState(false);

  // Called by Survey when an assessment completes — lifts result to App level
  const handleAssessmentComplete = (threatModel, answers) => {
    setLastThreatModel(threatModel);
    setLastAnswers(answers);
  };

  if (view === 'survey') {
    return (
      <Survey
        onGoHome={() => setView('home')}
        onAssessmentComplete={handleAssessmentComplete}
        initialDone={resumeResults && !!lastThreatModel}
        initialThreatModel={resumeResults ? lastThreatModel : null}
        initialAnswers={resumeResults ? lastAnswers : {}}
      />
    );
  }

  if (view === 'misconfig') {
    return (
      <MisconfigGuide
        threatModel={null}
        onBack={() => setView('home')}
      />
    );
  }

  if (view === 'economic' && lastThreatModel) {
    return (
      <GordonLoebWalkthrough
        threatModel={lastThreatModel}
        surveyAnswers={lastAnswers}
        onBack={() => setView('home')}
      />
    );
  }

  return (
    <Home
      onStartSurvey={() => { setResumeResults(false); setView('survey'); }}
      onOpenMisconfig={() => setView('misconfig')}
      onOpenEconomic={() => { if (lastThreatModel) setView('economic'); }}
      lastThreatModel={lastThreatModel}
      onViewLastResults={() => { setResumeResults(true); setView('survey'); }}
    />
  );
}